"""P0.4 — a consumer must not assert an assurance level it did not obtain.

Two defects these tests pin (both reproduced against commit 2afd68d):

(a) `ChainView.from_envelopes()` assigned `valid=True` to whatever envelope
    list it was handed, with no verification of any kind.
(b) Report templates emitted "Ed25519 signatures verify" and "every decision
    is signed and replayable" on a chain whose signatures were never checked,
    and revocation was omitted entirely rather than declared unimplemented.

The distinctions under test are NOT interchangeable:
    schema validation  ≠  hash verification  ≠  chain continuity
    ≠  signature verification  ≠  key trust  ≠  revocation  ≠  overall assurance

Assurance ordering:
    INVALID < NOT_MEASURED < RECORDED < HASH_VERIFIED
            < SIGNATURE_VERIFIED < VERIFIED < TRUSTED
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

#: Phrases that assert a signature/authenticity fact. None may appear in a
#: report unless signature verification actually ran and passed.
SIGNATURE_CLAIM_PHRASES = [
    "Ed25519 signatures verify",
    "signatures verify against",
    "every decision is signed and replayable",
]

#: Phrases that assert overall chain validity.
VALIDITY_CLAIM_PHRASES = [
    "Chain validates at assessment time",
    "✓ valid",
]


# ── fixtures ───────────────────────────────────────────────────────

def _unverified_envelopes() -> list[dict]:
    """Envelopes that are DEMONSTRABLY BAD.

    envelope[1].integrity.previous does not match envelope[0].integrity.current
    (broken hash-chain link), and every signature is a literal placeholder.
    Nothing here has been verified by anything.
    """
    return [
        {
            "schema": "phionyx.governed_response_envelope.v0.2",
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {"turn_index": 0, "decision": "pass", "kind": "tool_call"},
            "integrity": {
                "previous": "GENESIS",
                "current": "aaaa1111",
                "key_id": "key-attacker-2026",
                "signature": "FORGED-NOT-A-REAL-SIGNATURE",
            },
        },
        {
            "schema": "phionyx.governed_response_envelope.v0.2",
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {"turn_index": 1, "decision": "pass", "kind": "tool_call"},
            "integrity": {
                "previous": "DELIBERATELY-WRONG-PREVIOUS-HASH",
                "current": "bbbb2222",
                "key_id": "key-attacker-2026",
                "signature": "FORGED-NOT-A-REAL-SIGNATURE",
            },
        },
    ]


def _render_all(chain):
    from phionyx_compliance import load_template, render, resolve_inputs

    out = {}
    for name in ALL_TEMPLATES:
        t = load_template(name)
        out[name] = render(t, resolve_inputs(t, chain))
    return out


# ── (a) the unverified-positive path ───────────────────────────────

def test_from_envelopes_does_not_assert_a_positive():
    """REGRESSION. Previously: valid=True on unverified input."""
    from phionyx_compliance import ChainView

    chain = ChainView.from_envelopes("t-unverified", _unverified_envelopes())
    r = chain.verify_result

    assert r.valid is None, "unverified input must not yield a positive verdict"
    assert r.assurance == "RECORDED"
    assert r.hash_verified is None, "no hash walk ran — must stay NOT MEASURED"
    assert r.signature_verified is None, "no signature check ran"
    assert r.revocation_checked is False


def test_assurance_dimensions_are_recorded_separately():
    """schema / hash / signature / revocation are distinct, not one boolean."""
    from phionyx_compliance import VerifyResult

    for field in (
        "received",
        "schema_valid",
        "hash_verified",
        "signature_verified",
        "revocation_checked",
    ):
        assert hasattr(VerifyResult(), field), f"missing dimension: {field}"


def test_hash_verification_alone_is_not_a_positive_verdict():
    """Hash-chain continuity is not authenticity. It must not yield valid=True."""
    from phionyx_compliance import VerifyResult

    r = VerifyResult(received=3, hash_verified=True, signature_verified=None)
    assert r.assurance == "HASH_VERIFIED"
    assert r.valid is None, "hash continuity must not be reported as overall validity"


def test_not_measured_is_never_upgraded_to_pass():
    from phionyx_compliance import VerifyResult

    assert VerifyResult().assurance == "NOT_MEASURED"
    assert VerifyResult().valid is None
    assert VerifyResult(received=5).assurance == "RECORDED"
    assert VerifyResult(received=5).valid is None


def test_assurance_ordering_is_the_specified_one():
    from phionyx_compliance import ASSURANCE_ORDER

    assert ASSURANCE_ORDER == [
        "INVALID",
        "NOT_MEASURED",
        "RECORDED",
        "HASH_VERIFIED",
        "SIGNATURE_VERIFIED",
        "VERIFIED",
        "TRUSTED",
    ]


def test_verified_and_trusted_are_unreachable_here():
    """This package implements no key trust, revocation, witness or freshness
    check, so it must never report VERIFIED or TRUSTED."""
    from phionyx_compliance import VerifyResult

    strongest = VerifyResult(
        received=2, schema_valid=True, hash_verified=True, signature_verified=True
    )
    assert strongest.assurance == "SIGNATURE_VERIFIED"
    assert strongest.assurance not in ("VERIFIED", "TRUSTED")


# ── (b) report language must be derived from the result ────────────

@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_no_template_claims_signature_verification_when_none_ran(name):
    """ACCEPTANCE 4. The pin: a signature claim requires a signature check."""
    from phionyx_compliance import ChainView, load_template, render, resolve_inputs

    chain = ChainView.from_envelopes("t-unverified", _unverified_envelopes())
    assert chain.verify_result.signature_verified is not True

    t = load_template(name)
    out = render(t, resolve_inputs(t, chain))

    for phrase in SIGNATURE_CLAIM_PHRASES:
        assert phrase not in out, f"{name}: signature claim {phrase!r} without verification"
    for phrase in VALIDITY_CLAIM_PHRASES:
        assert phrase not in out, f"{name}: validity claim {phrase!r} without verification"


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_unverified_report_states_that_nothing_was_verified(name):
    """ACCEPTANCE 2. Non-positive status AND a report that says so."""
    rendered = _render_all(
        __import__(
            "phionyx_compliance", fromlist=["ChainView"]
        ).ChainView.from_envelopes("t-unverified", _unverified_envelopes())
    )[name]

    assert "RECORDED" in rendered
    assert "Nothing was verified" in rendered
    assert "no signature verification were performed" in rendered


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_report_declares_revocation_unimplemented(name):
    """Revocation is not implemented — every report must SAY so, not omit it."""
    rendered = _render_all(
        __import__(
            "phionyx_compliance", fromlist=["ChainView"]
        ).ChainView.from_envelopes("t-unverified", _unverified_envelopes())
    )[name]

    assert "key revocation is not implemented" in rendered.lower()


def test_eu_template_does_not_render_a_clean_revocation_count():
    """A bare `0` asserted that zero revoked keys were referenced — a finding
    nothing established."""
    from phionyx_compliance import ChainView, load_template, resolve_inputs

    chain = ChainView.from_envelopes("t-unverified", _unverified_envelopes())
    t = load_template("eu-ai-act-article-13")
    inputs = resolve_inputs(t, chain)

    assert inputs["key_revocation_referenced_count"] != 0
    assert "NOT CHECKED" in str(inputs["key_revocation_referenced_count"])


@pytest.mark.parametrize("name", ALL_TEMPLATES)
def test_sample_mode_does_not_claim_verification(name):
    """Sample mode verifies nothing, so it must not display a verified posture
    (a demo must not read as production assurance)."""
    from phionyx_compliance import load_template, render, sample_inputs

    t = load_template(name)
    out = render(t, sample_inputs(name))

    for phrase in SIGNATURE_CLAIM_PHRASES + VALIDITY_CLAIM_PHRASES:
        assert phrase not in out, f"{name}: sample render claims {phrase!r}"
    assert "RECORDED" in out


def test_owasp_t8_refuses_repudiation_claim_without_signature():
    """Non-repudiation is a signature property, not a hash property."""
    from phionyx_compliance.renderer import render_t8_repudiation_status

    hash_only = render_t8_repudiation_status(
        envelope_count=10, assurance="HASH_VERIFIED", signature_verified=None
    )
    assert "every decision is signed and replayable" not in hash_only
    assert "NOT** verified" in hash_only or "NOT sufficient" in hash_only

    nothing = render_t8_repudiation_status(
        envelope_count=10, assurance="RECORDED", signature_verified=None
    )
    assert "no repudiation defence" in nothing.lower()


def test_owasp_t9_reports_key_id_as_declared_not_verified():
    from phionyx_compliance.renderer import render_t9_spoofing_status

    out = render_t9_spoofing_status(signing_key_id="key-1", signature_verified=None)
    assert "declare" in out.lower()
    assert "signed under" not in out.lower()
    assert "did **NOT** run" in out


# ── negative tests: broken chain link / broken signature ───────────

def _hash_valid_chain(n: int = 3) -> list[dict]:
    """Build a chain whose hash linkage genuinely recomputes, using the
    producer's own hashing helpers."""
    from phionyx_mcp_server.audit_chain import (
        GENESIS_HASH,
        envelope_hash,
        payload_for_hash,
    )

    envelopes: list[dict] = []
    previous = GENESIS_HASH
    for i in range(n):
        payload = {
            "schema": "phionyx.governed_response_envelope.v0.2",
            "schema_id": "phionyx.governed_response_envelope.v0.2",
            "subject": {"turn_index": i, "decision": "pass", "kind": "tool_call"},
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
    return envelopes


class _AlwaysFails:
    """A verifier that rejects every signature (models a forged signature)."""

    def verify(self, current_hash: str, signature: str) -> bool:
        return False


class _AlwaysPasses:
    """A stub verifier that accepts. Used only as a positive control — it
    proves the gate DISCRIMINATES rather than merely banning a string."""

    def verify(self, current_hash: str, signature: str) -> bool:
        return True


def test_broken_hash_chain_link_yields_invalid_and_a_refusing_report():
    """NEGATIVE. Broken chain link → INVALID → report refuses explicitly."""
    from phionyx_mcp_server.audit_chain import verify_chain

    from phionyx_compliance import (
        ChainView,
        load_template,
        render,
        resolve_inputs,
        verify_result_from_upstream,
    )

    envelopes = _hash_valid_chain(3)
    envelopes[2]["integrity"]["previous"] = "TAMPERED-LINK"

    verdict = verify_chain(envelopes)
    assert verdict["valid"] is False, verdict

    result = verify_result_from_upstream(verdict, received=len(envelopes))
    assert result.assurance == "INVALID"
    assert result.valid is False
    assert result.hash_verified is False

    chain = ChainView.from_envelopes("t-broken", envelopes, verify_result=result)
    t = load_template("eu-ai-act-article-13")
    out = render(t, resolve_inputs(t, chain))

    assert "INVALID" in out
    assert "hash-chain verification FAILED" in out
    assert "unusable evidence" in out
    for phrase in SIGNATURE_CLAIM_PHRASES + VALIDITY_CLAIM_PHRASES:
        assert phrase not in out


def test_forged_signature_yields_invalid_and_a_refusing_report():
    """NEGATIVE. Hash chain intact but signature verification FAILS.

    This is the case a hash-only check cannot see, and the exact case the
    old code reported as fully valid.
    """
    from phionyx_mcp_server.audit_chain import verify_chain

    from phionyx_compliance import (
        ChainView,
        load_template,
        render,
        resolve_inputs,
        verify_result_from_upstream,
    )

    envelopes = _hash_valid_chain(3)
    verdict = verify_chain(envelopes, verifier=_AlwaysFails())

    assert verdict["valid"] is False
    assert verdict["hash_chain_valid"] is True, "hash layer is intact by construction"

    result = verify_result_from_upstream(verdict, received=len(envelopes))
    assert result.signature_verified is False
    assert result.assurance == "INVALID"

    chain = ChainView.from_envelopes("t-forged", envelopes, verify_result=result)
    t = load_template("owasp-agentic-ai-v1")
    out = render(t, resolve_inputs(t, chain))

    assert "signature verification FAILED" in out
    assert "INTEGRITY FAILURE" in out, "T8 must report a repudiation-defence failure"
    assert "every decision is signed and replayable" not in out


def test_hash_intact_but_unverified_signature_is_not_a_pass():
    """NEGATIVE. Upstream's honest NOT_MEASURED must survive the consumer.

    phionyx-mcp-server 0.2.1 returns valid=None / NOT_MEASURED when no
    verifier is supplied. That must become neither True nor False.
    """
    from phionyx_mcp_server.audit_chain import verify_chain

    from phionyx_compliance import verify_result_from_upstream

    envelopes = _hash_valid_chain(3)
    verdict = verify_chain(envelopes)  # no verifier

    assert verdict["valid"] is None
    assert verdict["measurement_status"] == "NOT_MEASURED"

    result = verify_result_from_upstream(verdict, received=len(envelopes))
    assert result.hash_verified is True
    assert result.signature_verified is None, "NOT MEASURED must not become False"
    assert result.assurance == "HASH_VERIFIED"
    assert result.valid is None, "NOT MEASURED must not become True"


def test_upstream_overclaim_cannot_propagate_past_signature_verified():
    """An upstream that returns a too-strong positive must not lift this
    consumer above SIGNATURE_VERIFIED.

    Measured in this ecosystem (2026-08-06): AIREP's own verifiers returned
    `Trusted` for 7/7 adversarial records — including a forged witness
    signature, witness==producer, and a key the record itself declared
    revoked. So an upstream "verified" result is not evidence that any
    cryptographic check ran. This consumer caps what it will report: key
    trust, revocation, witness and freshness are NOT evaluated here, so
    VERIFIED and TRUSTED are unreachable regardless of what upstream says.
    """
    from phionyx_compliance import verify_result_from_upstream

    overclaiming_upstream = {
        "valid": True,
        "measurement_status": "TRUSTED",
        "hash_chain_valid": True,
        "signatures_verified": True,
        "broken_at": None,
        "reason": None,
        # Fields a caller might be tempted to trust wholesale:
        "assurance": "TRUSTED",
        "witness_valid": True,
        "revocation_checked": True,
        "key_trusted": True,
    }
    r = verify_result_from_upstream(overclaiming_upstream, received=3)

    assert r.assurance == "SIGNATURE_VERIFIED"
    assert r.assurance not in ("VERIFIED", "TRUSTED")
    # Revocation is not implemented HERE; an upstream flag must not flip it.
    assert r.revocation_checked is False


def test_positive_control_signature_verified_unlocks_the_claim():
    """The gate must DISCRIMINATE: when verification really ran and passed,
    the report is allowed to state it — but still must not name an algorithm
    it never observed, and must still declare revocation unchecked."""
    from phionyx_mcp_server.audit_chain import verify_chain

    from phionyx_compliance import (
        ChainView,
        load_template,
        render,
        resolve_inputs,
        verify_result_from_upstream,
    )

    envelopes = _hash_valid_chain(3)
    verdict = verify_chain(envelopes, verifier=_AlwaysPasses())
    assert verdict["valid"] is True

    result = verify_result_from_upstream(verdict, received=len(envelopes))
    assert result.assurance == "SIGNATURE_VERIFIED"
    assert result.valid is True

    chain = ChainView.from_envelopes("t-signed", envelopes, verify_result=result)
    t = load_template("owasp-agentic-ai-v1")
    out = render(t, resolve_inputs(t, chain))

    assert "SIGNATURE_VERIFIED" in out
    assert "signature verification ran and passed" in out
    assert "signatures verified and the chain is replayable" in out
    # The verifier here is a stub; naming Ed25519 would describe an unknown
    # verifier as production Ed25519 assurance.
    assert "Ed25519 signatures verify" not in out
    # Assurance still stops below VERIFIED.
    assert "key revocation is not implemented" in out.lower()
    assert "key trust was not evaluated" in out
