"""
meok-compliance-passport-mcp server.

Issues, verifies, and exchanges Agent Compliance Passports - portable,
signed credentials an AI agent carries proving it is compliant with
EU AI Act, GDPR, HIPAA, and nine other frameworks.

The verify path is 100% offline. Any agent, anywhere, with a public key
can validate the signature and the framework claims in microseconds - no
network, no phone-home, no vendor lock-in.

Positioning (from BREAKTHROUGH_INSIGHTS.md):
    "In a world of unverifiable AI claims, we sell the auditor's math."

This server is a Mavis-pattern 7-file MCP. All logic lives here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, Field, field_validator, model_validator

try:
    # mcp is the official Model Context Protocol SDK
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:  # pragma: no cover - allows the module to be imported for tests
    MCP_AVAILABLE = False
    Server = None  # type: ignore
    stdio_server = None  # type: ignore
    Tool = None  # type: ignore
    TextContent = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants - structured regulation dictionary
# ---------------------------------------------------------------------------

ISSUER: str = "meok.ai"
ISSUER_DID: str = "did:meok:issuer:meok.ai"

# Supported agent archetypes.
SUPPORTED_AGENT_TYPES: tuple[str, ...] = (
    "llm_agent",
    "rag_system",
    "mcp_server",
    "ai_pipeline",
    "autonomous_agent",
)

# Supported compliance frameworks. The passport is the intersection of the
# frameworks a given agent is asserting it conforms to.
SUPPORTED_FRAMEWORKS: tuple[str, ...] = (
    "eu_ai_act",
    "gdpr",
    "hipaa",
    "soc2",
    "iso_42001",
    "nist_ai_rmf",
    "cra",                       # EU Cyber Resilience Act
    "dora",                      # Digital Operational Resilience Act
    "nis2",                      # NIS2 Directive
    "ai_act_article_50",         # EU AI Act Article 50 (transparency obligations)
    "code_of_practice",          # GPAI Code of Practice
)

# Per-article schema hints for the structured regulation dictionary.
# Keyed by framework -> article -> {title, scope, evidence_required}
REGULATION_SCHEMA: Dict[str, Dict[str, Dict[str, str]]] = {
    "eu_ai_act": {
        "article_9": {
            "title": "Risk management system",
            "scope": "high-risk AI systems",
            "evidence_required": "continuous iterative risk process across lifecycle",
        },
        "article_10": {
            "title": "Data and data governance",
            "scope": "training/validation/test datasets",
            "evidence_required": "data quality criteria, bias examination, representativeness",
        },
        "article_11": {
            "title": "Technical documentation",
            "scope": "high-risk AI systems placed on the market",
            "evidence_required": "Annex IV documentation kept up to date",
        },
        "article_12": {
            "title": "Record-keeping / logging",
            "scope": "automatic logging of events",
            "evidence_required": "traceability of system functioning",
        },
        "article_13": {
            "title": "Transparency and provision of information to deployers",
            "scope": "high-risk AI systems",
            "evidence_required": "instructions for use, including capabilities and limitations",
        },
        "article_14": {
            "title": "Human oversight",
            "scope": "high-risk AI systems",
            "evidence_required": "effective human oversight during use",
        },
        "article_15": {
            "title": "Accuracy, robustness, cybersecurity",
            "scope": "high-risk AI systems",
            "evidence_required": "appropriate levels of accuracy and resilience",
        },
    },
    "ai_act_article_50": {
        "transparency_50": {
            "title": "Transparency obligations for providers and deployers",
            "scope": "all AI systems interacting with natural persons",
            "evidence_required": "users informed they are interacting with AI; deepfake disclosure; emotion recognition notice",
        },
    },
    "gdpr": {
        "article_5": {
            "title": "Principles relating to processing of personal data",
            "scope": "lawfulness, fairness, transparency, purpose limitation, data minimisation, accuracy, storage limitation, integrity and confidentiality",
        },
        "article_6": {
            "title": "Lawfulness of processing",
            "scope": "at least one lawful basis required",
        },
        "article_22": {
            "title": "Automated individual decision-making, including profiling",
            "scope": "right not to be subject to a decision based solely on automated processing",
        },
        "article_25": {
            "title": "Data protection by design and by default",
            "scope": "appropriate technical and organisational measures",
        },
        "article_32": {
            "title": "Security of processing",
            "scope": "pseudonymisation, encryption, resilience, regular testing",
        },
        "article_35": {
            "title": "Data protection impact assessment",
            "scope": "high-risk processing",
        },
    },
    "hipaa": {
        "section_164_308": {
            "title": "Administrative safeguards",
            "scope": "workforce training, access management, contingency plans",
        },
        "section_164_310": {
            "title": "Physical safeguards",
            "scope": "facility access controls, workstation use, device controls",
        },
        "section_164_312": {
            "title": "Technical safeguards",
            "scope": "access control, audit controls, integrity, person authentication, transmission security",
        },
        "section_164_316": {
            "title": "Documentation requirements",
            "scope": "policies, procedures, maintenance of documentation",
        },
    },
    "soc2": {
        "cc1": {"title": "Control environment"},
        "cc2": {"title": "Communication and information"},
        "cc3": {"title": "Risk assessment"},
        "cc4": {"title": "Monitoring activities"},
        "cc5": {"title": "Control activities"},
        "cc6": {"title": "Logical and physical access controls"},
        "cc7": {"title": "System operations"},
        "cc8": {"title": "Change management"},
        "cc9": {"title": "Risk mitigation"},
    },
    "iso_42001": {
        "clause_5": {"title": "Leadership"},
        "clause_6": {"title": "Planning"},
        "clause_7": {"title": "Support"},
        "clause_8": {"title": "Operation"},
        "clause_9": {"title": "Performance evaluation"},
        "clause_10": {"title": "Improvement"},
    },
    "nist_ai_rmf": {
        "govern": {"title": "Govern"},
        "map": {"title": "Map"},
        "measure": {"title": "Measure"},
        "manage": {"title": "Manage"},
    },
    "cra": {
        "annex_i": {"title": "Essential cybersecurity requirements"},
        "article_13": {"title": "Reporting obligations"},
    },
    "dora": {
        "article_5": {"title": "ICT risk management framework"},
        "article_12": {"title": "Incident reporting"},
    },
    "nis2": {
        "article_21": {"title": "Cybersecurity risk-management measures"},
    },
    "code_of_practice": {
        "section_2": {"title": "Transparency"},
        "section_3": {"title": "Copyright"},
        "section_4": {"title": "Safety and Security"},
    },
}

# Allowed values for a claim's status. "compliant" is the only one that
# flips the passport's valid bit in the exchange handshake; everything else
# is treated as non-blocking for the credential, but logged as not-yet-clean.
VALID_CLAIM_STATUSES: tuple[str, ...] = (
    "compliant",
    "in_review",
    "self_declared",
    "remediation_in_progress",
    "non_compliant",
)


# ---------------------------------------------------------------------------
# Cryptographic key material
# ---------------------------------------------------------------------------

# replace with meok-compliance-gateway KMS in production
# A deterministic 32-byte Ed25519 seed used for the bundled test/demo flow.
# In production this is replaced with a KMS-backed key (see keystone:
# meok-compliance-gateway).
TEST_PRIVATE_KEY: bytes = hashlib.sha256(b"meok.ai/agent-compliance-passport/test-key-v1").digest()


def _load_private_key() -> Ed25519PrivateKey:
    """Load the test signing key. In production this calls the KMS."""
    return Ed25519PrivateKey.from_private_bytes(TEST_PRIVATE_KEY)


def _public_key_bytes(pub: Ed25519PublicKey) -> bytes:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw


# Pre-derive the public key (stable, used as the issuer's kid).
_PRIVATE_KEY = _load_private_key()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
ISSUER_PUBLIC_KEY_BYTES: bytes = _public_key_bytes(_PUBLIC_KEY)
ISSUER_PUBLIC_KEY_B64: str = base64.b64encode(ISSUER_PUBLIC_KEY_BYTES).decode("ascii")
ISSUER_PUBLIC_KEY_HEX: str = ISSUER_PUBLIC_KEY_BYTES.hex()
KID: str = f"meok-issuer-{ISSUER_PUBLIC_KEY_HEX[:16]}"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Passport(BaseModel):
    """The signed, portable compliance credential."""

    agent_id: str = Field(..., description="DID-style identifier: did:meok:<uuid>")
    agent_type: str = Field(..., description="Archetype of the AI agent")
    frameworks_covered: List[str] = Field(default_factory=list)
    claims: Dict[str, Dict[str, str]] = Field(default_factory=dict)
    issuer: str = Field(default=ISSUER)
    issued_at: str = Field(..., description="ISO 8601 UTC timestamp")
    expires_at: str = Field(..., description="ISO 8601 UTC timestamp")
    public_key: str = Field(..., description="Hex-encoded Ed25519 public key (32 bytes)")
    signature: str = Field(..., description="Hex-encoded Ed25519 signature (64 bytes)")
    kid: str = Field(default=KID)

    @field_validator("agent_type")
    @classmethod
    def _validate_agent_type(cls, v: str) -> str:
        if v not in SUPPORTED_AGENT_TYPES:
            raise ValueError(
                f"agent_type must be one of {SUPPORTED_AGENT_TYPES}, got {v!r}"
            )
        return v

    @field_validator("frameworks_covered")
    @classmethod
    def _validate_frameworks(cls, v: List[str]) -> List[str]:
        bad = [f for f in v if f not in SUPPORTED_FRAMEWORKS]
        if bad:
            raise ValueError(
                f"unsupported framework(s): {bad}. Allowed: {SUPPORTED_FRAMEWORKS}"
            )
        return v

    @model_validator(mode="after")
    def _validate_claims(self) -> "Passport":
        for framework, articles in self.claims.items():
            if framework not in SUPPORTED_FRAMEWORKS:
                raise ValueError(f"claim references unknown framework {framework!r}")
            for article, status in articles.items():
                if status not in VALID_CLAIM_STATUSES:
                    raise ValueError(
                        f"invalid claim status {status!r} for "
                        f"{framework}/{article}; allowed: {VALID_CLAIM_STATUSES}"
                    )
        return self

    def canonical_payload(self) -> bytes:
        """Return the canonical byte string that was signed.

        The signature covers every field except the signature itself and the
        kid (which is a derivative of the public_key). The encoding is
        sorted-keys, no-whitespace, UTF-8 JSON - the standard for portable
        credentials.
        """
        body = {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "frameworks_covered": sorted(self.frameworks_covered),
            "claims": self.claims,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "public_key": self.public_key,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Core: issue / verify / exchange
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    # Always normalise to trailing 'Z' to keep wire format simple.
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_did() -> str:
    return f"did:meok:{uuid.uuid4()}"


def issue_passport(
    agent_id: Optional[str] = None,
    agent_type: str = "llm_agent",
    frameworks: Optional[List[str]] = None,
    claims: Optional[Dict[str, Dict[str, str]]] = None,
    ttl_days: int = 365,
) -> Passport:
    """Issue a signed compliance passport for an agent.

    Args:
        agent_id: DID-style identifier. Generated if omitted.
        agent_type: one of SUPPORTED_AGENT_TYPES.
        frameworks: list of framework identifiers. Defaults to all.
        claims: per-framework per-article status dict.
        ttl_days: days until expiry. Default 365.

    Returns:
        A signed Passport.
    """
    if frameworks is None:
        frameworks = list(SUPPORTED_FRAMEWORKS)
    if claims is None:
        claims = {}

    if agent_id is None:
        agent_id = make_did()
    elif not agent_id.startswith("did:meok:"):
        raise ValueError(f"agent_id must be a DID of the form did:meok:<id>, got {agent_id!r}")

    now = _now_utc()
    exp = now + timedelta(days=ttl_days)

    # Build the body first, then sign it. Use Pydantic to validate the
    # frameworks/agent_type/claims shape *before* signing.
    proto = Passport(
        agent_id=agent_id,
        agent_type=agent_type,
        frameworks_covered=list(frameworks),
        claims=dict(claims),
        issuer=ISSUER,
        issued_at=_iso(now),
        expires_at=_iso(exp),
        public_key=ISSUER_PUBLIC_KEY_HEX,
        signature="0" * 128,  # placeholder, overwritten below
    )
    payload = proto.canonical_payload()
    sig_bytes = _PRIVATE_KEY.sign(payload)
    return proto.model_copy(update={"signature": sig_bytes.hex()})


def verify_passport(passport: Passport) -> Dict[str, Any]:
    """Verify a passport's signature and expiry. 100% offline.

    Returns a dict with keys: valid, issuer, expires_at, frameworks_covered.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(passport.public_key))
    except (ValueError, TypeError):
        return {
            "valid": False,
            "issuer": passport.issuer,
            "expires_at": passport.expires_at,
            "frameworks_covered": list(passport.frameworks_covered),
            "reason": "invalid public key encoding",
        }

    try:
        payload = passport.canonical_payload()
        pub.verify(bytes.fromhex(passport.signature), payload)
    except InvalidSignature:
        return {
            "valid": False,
            "issuer": passport.issuer,
            "expires_at": passport.expires_at,
            "frameworks_covered": list(passport.frameworks_covered),
            "reason": "signature does not match payload",
        }
    except Exception as exc:  # malformed hex, etc.
        return {
            "valid": False,
            "issuer": passport.issuer,
            "expires_at": passport.expires_at,
            "frameworks_covered": list(passport.frameworks_covered),
            "reason": f"verification error: {exc}",
        }

    # Expiry check.
    try:
        exp = datetime.strptime(passport.expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return {
            "valid": False,
            "issuer": passport.issuer,
            "expires_at": passport.expires_at,
            "frameworks_covered": list(passport.frameworks_covered),
            "reason": "invalid expires_at format",
        }

    if exp <= _now_utc():
        return {
            "valid": False,
            "issuer": passport.issuer,
            "expires_at": passport.expires_at,
            "frameworks_covered": list(passport.frameworks_covered),
            "reason": "passport expired",
        }

    return {
        "valid": True,
        "issuer": passport.issuer,
        "expires_at": passport.expires_at,
        "frameworks_covered": list(passport.frameworks_covered),
    }


def _is_fully_compliant(passport: Passport) -> bool:
    """Decide if a passport is ready for the A2A handshake.

    Strict rule: every claim in the passport (across all frameworks) must
    have status 'compliant'. A passport with no claims is considered
    fully compliant (it asserts the frameworks, but with no open
    articles). This is the conservative default - the agent issuer
    is responsible for adding remediation claims for open work.
    """
    if not passport.claims:
        return True
    for _framework, articles in passport.claims.items():
        for _article, status in articles.items():
            if status != "compliant":
                return False
    return True


def exchange_credentials(
    agent_id_passport: Passport,
    counterparty_id: str,
    ttl_seconds: int = 60,
) -> Dict[str, Any]:
    """A2A handshake.

    Two agents meet. Each shows its passport. The counterparty verifies
    *its own* view of the presented passport offline, and the result is
    a short-lived authorization token granting a scope derived from the
    intersection of the frameworks the presented passport covers.

    The counterparty is trusted to have already verified the passport with
    verify_passport(). This function does *not* re-verify; it produces
    the negotiated scope. (The MCP exposes verify_passport for explicit
    inspection; the A2A flow calls both.)
    """
    verify_result = verify_passport(agent_id_passport)
    if not verify_result["valid"]:
        return {
            "authorized": False,
            "scope": [],
            "expires": _iso(_now_utc()),
            "reason": verify_result.get("reason", "passport did not verify"),
            "counterparty_id": counterparty_id,
        }

    if not _is_fully_compliant(agent_id_passport):
        return {
            "authorized": False,
            "scope": [],
            "expires": _iso(_now_utc()),
            "reason": "passport has non-compliant claims",
            "counterparty_id": counterparty_id,
        }

    scope = sorted(set(agent_id_passport.frameworks_covered))
    expires = _now_utc() + timedelta(seconds=ttl_seconds)
    return {
        "authorized": True,
        "scope": scope,
        "expires": _iso(expires),
        "counterparty_id": counterparty_id,
        "issuer": agent_id_passport.issuer,
        "agent_id": agent_id_passport.agent_id,
    }


# ---------------------------------------------------------------------------
# MCP server wiring
# ---------------------------------------------------------------------------

SERVER_DESCRIPTION = """\
Agent Compliance Passport (meok.ai)

Issue, verify, and exchange portable compliance credentials for AI agents.

In a world of unverifiable AI claims, we sell the auditor's math.

Three tools:
  - issue_passport(agent_id, agent_type, frameworks, claims) -> signed Passport
  - verify_passport(passport) -> {valid, issuer, expires_at, frameworks_covered}
  - exchange_credentials(agent_id_passport, counterparty_id) -> A2A handshake

Verification is 100% offline: no network, no phone-home, no vendor lock-in.
"""


def _tool_definitions() -> list:
    if not MCP_AVAILABLE:
        return []

    return [
        Tool(
            name="issue_passport",
            description=(
                "Issue a signed Agent Compliance Passport. The passport is a "
                "portable Ed25519-signed credential carrying the agent's DID, "
                "type, the compliance frameworks it asserts conformance to, "
                "and per-article claim status. Valid for 365 days by default."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "DID-style identifier. Auto-generated if omitted.",
                    },
                    "agent_type": {
                        "type": "string",
                        "enum": list(SUPPORTED_AGENT_TYPES),
                        "default": "llm_agent",
                    },
                    "frameworks": {
                        "type": "array",
                        "items": {"type": "string", "enum": list(SUPPORTED_FRAMEWORKS)},
                        "description": "Frameworks this passport asserts. Defaults to all.",
                    },
                    "claims": {
                        "type": "object",
                        "description": (
                            "Map of framework -> article -> status "
                            "(compliant | in_review | self_declared | "
                            "remediation_in_progress | non_compliant)."
                        ),
                        "additionalProperties": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="verify_passport",
            description=(
                "Verify a passport offline. Checks the Ed25519 signature and "
                "expiry. Returns {valid, issuer, expires_at, frameworks_covered}. "
                "No network is required - this is the auditor's math."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "passport": {
                        "type": "object",
                        "description": "The Passport object to verify.",
                    },
                },
                "required": ["passport"],
            },
        ),
        Tool(
            name="exchange_credentials",
            description=(
                "A2A handshake. Two agents present their passports and "
                "negotiate a short-lived authorization token whose scope is "
                "the intersection of the frameworks the presented passport "
                "covers. Returns {authorized, scope, expires}."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_id_passport": {
                        "type": "object",
                        "description": "The Passport presented by the calling agent.",
                    },
                    "counterparty_id": {
                        "type": "string",
                        "description": "DID of the counterparty agent.",
                    },
                },
                "required": ["agent_id_passport", "counterparty_id"],
            },
        ),
    ]


async def _handle_issue(name: str, arguments: dict) -> list:
    passport = issue_passport(
        agent_id=arguments.get("agent_id"),
        agent_type=arguments.get("agent_type", "llm_agent"),
        frameworks=arguments.get("frameworks"),
        claims=arguments.get("claims"),
    )
    return [TextContent(type="text", text=passport.model_dump_json(indent=2))]


async def _handle_verify(name: str, arguments: dict) -> list:
    raw = arguments.get("passport")
    if not isinstance(raw, dict):
        return [TextContent(type="text", text=json.dumps({"error": "passport must be an object"}))]
    passport = Passport.model_validate(raw)
    result = verify_passport(passport)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


async def _handle_exchange(name: str, arguments: dict) -> list:
    raw = arguments.get("agent_id_passport")
    counterparty = arguments.get("counterparty_id", "")
    if not isinstance(raw, dict):
        return [TextContent(type="text", text=json.dumps({"error": "agent_id_passport must be an object"}))]
    passport = Passport.model_validate(raw)
    result = exchange_credentials(passport, counterparty)
    return [TextContent(type="text", text=json.dumps(result, indent=2))]


HANDLERS = {
    "issue_passport": _handle_issue,
    "verify_passport": _handle_verify,
    "exchange_credentials": _handle_exchange,
}


def build_server():
    if not MCP_AVAILABLE:
        raise RuntimeError("mcp package is not installed; cannot build server")

    app = Server("meok-compliance-passport-mcp")

    @app.list_tools()
    async def list_tools() -> list:
        return _tool_definitions()

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> list:
        handler = HANDLERS.get(name)
        if handler is None:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool {name!r}"}))]
        return await handler(name, arguments)

    return app


async def _amain() -> None:
    app = build_server()
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When meok-compliance-passport-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for `meok-compliance-passport-mcp` console script."""
    import asyncio
    asyncio.run(_amain())


if __name__ == "__main__":
    main()
