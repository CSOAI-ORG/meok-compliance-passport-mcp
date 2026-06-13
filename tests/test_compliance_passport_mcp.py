"""Tests for meok-compliance-passport-mcp.

13 tests covering Ed25519 signature correctness, offline verification,
expiry handling, A2A exchange, framework/agent-type validation, DID
format, JSON round-trip, parallel issuance, signature length, and a full
end-to-end issue -> verify -> exchange flow.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from meok_compliance_passport_mcp.server import (
    ISSUER_PUBLIC_KEY_HEX,
    KID,
    Passport,
    SUPPORTED_AGENT_TYPES,
    SUPPORTED_FRAMEWORKS,
    exchange_credentials,
    issue_passport,
    verify_passport,
)


DID_RE = re.compile(r"^did:meok:[0-9a-fA-F-]{36}$")


# ---------- helpers ----------------------------------------------------------


def _make_passport(**overrides):
    defaults: dict = dict(
        agent_type="llm_agent",
        frameworks=["eu_ai_act", "gdpr"],
        claims={
            "eu_ai_act": {"article_9": "compliant", "article_10": "in_review"},
            "gdpr": {"article_5": "compliant"},
        },
    )
    defaults.update(overrides)
    return issue_passport(**defaults)


# ---------- tests ------------------------------------------------------------


def test_01_issue_returns_valid_ed25519_signature():
    passport = _make_passport()
    # Ed25519 signature is 64 bytes -> 128 hex chars.
    assert len(passport.signature) == 128
    int(passport.signature, 16)  # parses as hex
    # Public key is 32 bytes -> 64 hex chars.
    assert len(passport.public_key) == 64
    assert passport.public_key == ISSUER_PUBLIC_KEY_HEX
    assert passport.kid == KID
    assert passport.issuer == "meok.ai"


def test_02_verify_returns_true_for_valid_passport():
    passport = _make_passport()
    result = verify_passport(passport)
    assert result["valid"] is True
    assert result["issuer"] == "meok.ai"
    assert "eu_ai_act" in result["frameworks_covered"]
    assert "gdpr" in result["frameworks_covered"]


def test_03_verify_returns_false_if_signature_tampered():
    passport = _make_passport()
    # Flip the last byte of the signature.
    tampered_sig = passport.signature[:-1] + (
        "0" if passport.signature[-1] != "0" else "1"
    )
    bad = passport.model_copy(update={"signature": tampered_sig})
    result = verify_passport(bad)
    assert result["valid"] is False
    assert "signature" in result["reason"].lower()


def test_04_verify_returns_false_if_expired():
    passport = _make_passport(ttl_days=-1)  # already expired
    result = verify_passport(passport)
    assert result["valid"] is False
    assert "expired" in result["reason"]


def test_05_exchange_authorises_both_parties():
    passport = _make_passport(claims={})  # no open claims -> fully compliant
    result = exchange_credentials(passport, counterparty_id="did:meok:other")
    assert result["authorized"] is True
    assert "eu_ai_act" in result["scope"]
    assert "gdpr" in result["scope"]
    assert result["counterparty_id"] == "did:meok:other"


def test_06_exchange_rejects_expired_passports():
    passport = _make_passport(ttl_days=-1, claims={})
    result = exchange_credentials(passport, counterparty_id="did:meok:other")
    assert result["authorized"] is False
    assert result["scope"] == []


def test_07_exchange_rejects_passport_with_non_compliant_claim():
    passport = _make_passport(  # has article_10: in_review
        counterparty_id=None
    ) if False else _make_passport()
    result = exchange_credentials(passport, counterparty_id="did:meok:other")
    assert result["authorized"] is False
    assert result["scope"] == []
    assert "non-compliant" in result["reason"]


def test_08_frameworks_dict_validates_against_supported_list():
    # Valid: no error
    _make_passport(frameworks=["eu_ai_act", "hipaa"])
    # Invalid framework name should raise during Pydantic validation
    with pytest.raises(Exception):
        issue_passport(agent_type="llm_agent", frameworks=["not_a_real_framework"])


def test_09_agent_type_validates_against_supported_list():
    # Valid
    _make_passport(agent_type="rag_system")
    _make_passport(agent_type="autonomous_agent")
    # Invalid
    with pytest.raises(Exception):
        issue_passport(agent_type="skynet")
    # Sanity: the constant lists the 5 types we expect
    assert set(SUPPORTED_AGENT_TYPES) == {
        "llm_agent",
        "rag_system",
        "mcp_server",
        "ai_pipeline",
        "autonomous_agent",
    }


def test_10_did_format_is_correct():
    passport = _make_passport()
    assert DID_RE.match(passport.agent_id), f"bad DID: {passport.agent_id}"
    # Auto-generation works and produces a fresh DID each call.
    p1 = issue_passport()
    p2 = issue_passport()
    assert p1.agent_id != p2.agent_id
    assert DID_RE.match(p1.agent_id)
    assert DID_RE.match(p2.agent_id)


def test_11_passport_serializes_to_json_roundtrip():
    passport = _make_passport()
    s = passport.model_dump_json()
    parsed = json.loads(s)
    rebuilt = Passport.model_validate(parsed)
    # The rebuilt passport must still verify.
    assert verify_passport(rebuilt)["valid"] is True
    # And the signatures match exactly.
    assert rebuilt.signature == passport.signature
    assert rebuilt.public_key == passport.public_key


def test_12_multiple_passports_issued_in_parallel():
    # Exercise the signing path under thread concurrency.
    def _one(i):
        return issue_passport(
            agent_type="llm_agent",
            frameworks=["eu_ai_act"],
            claims={"eu_ai_act": {f"article_{i}": "compliant"}},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        passports = list(ex.map(_one, range(20)))

    assert len(passports) == 20
    sigs = {p.signature for p in passports}
    assert len(sigs) == 20  # all unique
    for p in passports:
        assert verify_passport(p)["valid"] is True


def test_13_signature_length_is_exactly_128_hex_chars():
    passport = _make_passport()
    assert len(passport.signature) == 128
    # Pure hex
    assert re.fullmatch(r"[0-9a-f]{128}", passport.signature) is not None


def test_14_integration_issue_verify_exchange_roundtrip():
    """Full e2e: issue -> verify -> exchange."""
    # 1. Issue
    passport = issue_passport(
        agent_id="did:meok:integration-agent-001",
        agent_type="mcp_server",
        frameworks=["eu_ai_act", "gdpr", "ai_act_article_50"],
        claims={
            "eu_ai_act": {"article_9": "compliant", "article_10": "compliant"},
            "gdpr": {"article_5": "compliant", "article_25": "compliant"},
            "ai_act_article_50": {"transparency_50": "compliant"},
        },
    )
    assert passport.agent_type == "mcp_server"

    # 2. Verify (offline, no network)
    v = verify_passport(passport)
    assert v["valid"] is True
    assert set(v["frameworks_covered"]) == {
        "eu_ai_act",
        "gdpr",
        "ai_act_article_50",
    }

    # 3. Exchange (A2A handshake)
    e = exchange_credentials(passport, counterparty_id="did:meok:counterparty-007")
    assert e["authorized"] is True
    assert e["agent_id"] == "did:meok:integration-agent-001"
    assert e["counterparty_id"] == "did:meok:counterparty-007"
    assert set(e["scope"]) == {"eu_ai_act", "gdpr", "ai_act_article_50"}

    # expires must be in the future
    exp = datetime.strptime(e["expires"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    assert exp > datetime.now(timezone.utc)
