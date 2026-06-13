# Agent Compliance Passport MCP

[![MCP](https://img.shields.io/badge/MCP-1.0.0-blue.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-14%20passing-brightgreen.svg)]()

> **In a world of unverifiable AI claims, we sell the auditor's math.**

The **Agent Compliance Passport** is a single signed, portable credential an
AI agent carries proving it is compliant with EU AI Act, GDPR, HIPAA, and
nine other frameworks. Any other agent verifies the passport **offline, in
microseconds, with no network and no phone-home** before transacting.

This is the Mavis 7-file MCP server that issues, verifies, and exchanges
those passports.

---

## Why

Every AI vendor ships a "trust center." Every AI agent makes compliance
claims. None of it is cryptographically verifiable. Two agents transacting
in 2026 still exchange Word documents and Slack screenshots.

The Agent Compliance Passport fixes this:

- **Portable** — one signed JSON blob travels with the agent.
- **Verifiable offline** — the public key is enough. No API call. No vendor
  lock-in. The verifier does the math, not the vendor.
- **Structured** — a per-article claim status across 11 frameworks, with a
  machine-readable schema for the whole regulation set.
- **Cheap to issue** — a `+1 cent` per passport cost. Free for the first
  1,000 / month.
- **A2A-ready** — the `exchange_credentials` tool is the handshake.

Positioning (from `BREAKTHROUGH_INSIGHTS.md`):

> **The Anti-Billion-Dollar-Whale.** The big platforms will sell you
> "AI compliance" at $500K/yr. We sell the math the auditor needs to check
> the claim, for free, open-sourced, and runnable on a Raspberry Pi.

---

## Install

```bash
git clone https://github.com/meok-ai/meok-compliance-passport-mcp
cd meok-compliance-passport-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The package depends on `mcp>=0.9.0`, `pydantic>=2.0`, `cryptography>=42.0`,
and `httpx>=0.25`.

---

## 30-second demo

Issue a passport, verify it offline, exchange it in a handshake. Six lines.

```python
from meok_compliance_passport_mcp.server import (
    issue_passport, verify_passport, exchange_credentials,
)

passport = issue_passport(        # signed, 365-day, Ed25519
    agent_id="did:meok:my-agent-001",
    agent_type="llm_agent",
    frameworks=["eu_ai_act", "gdpr"],
    claims={"eu_ai_act": {"article_9": "compliant"}},
)

print(verify_passport(passport))  # {'valid': True, ...}  -- OFFLINE

print(exchange_credentials(
    passport, counterparty_id="did:meok:peer-007"
))                                  # {'authorized': True, 'scope': [...], ...}
```

---

## The 3 tools

### 1. `issue_passport(agent_id, agent_type, frameworks, claims) -> Passport`

Signs and returns a `Passport`. The signature is Ed25519 over a canonical
(sorted-keys, no-whitespace) JSON encoding of every field except the
signature itself.

| Field             | Type   | Description                                         |
| ----------------- | ------ | --------------------------------------------------- |
| `agent_id`        | str    | `did:meok:<uuid>`                                   |
| `agent_type`      | str    | one of `llm_agent`, `rag_system`, `mcp_server`, `ai_pipeline`, `autonomous_agent` |
| `frameworks_covered` | list | subset of 11 supported frameworks                   |
| `claims`          | dict   | `{framework: {article: status}}`                    |
| `issuer`          | str    | `meok.ai`                                           |
| `issued_at`       | str    | ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`)               |
| `expires_at`      | str    | ISO 8601 UTC, default `+365 days`                   |
| `public_key`      | str    | 32-byte Ed25519 public key, hex                     |
| `signature`       | str    | 64-byte Ed25519 signature, hex                      |
| `kid`             | str    | Key ID, derived from public key                     |

### 2. `verify_passport(passport) -> {valid, issuer, expires_at, frameworks_covered}`

**100% offline.** No network. Reconstructs the canonical payload from the
passport, runs the Ed25519 verification, and checks the expiry. Returns
`valid: False` with a `reason` on any failure (bad signature, malformed
key, expired, etc.).

This is the *auditor's math*. The math is open, the math is portable, and
the math runs on a Raspberry Pi in microseconds.

### 3. `exchange_credentials(agent_id_passport, counterparty_id) -> {authorized, scope, expires}`

The A2A handshake. Two agents meet, each presents its passport, and the
verifier produces a short-lived authorization token whose `scope` is the
intersection of the frameworks the presented passport covers. Default
token TTL: 60 seconds.

---

## EU AI Act Article 50 alignment

Article 50 of the EU AI Act imposes **transparency obligations** on
providers and deployers of AI systems that interact with natural persons.
Sub-paragraphs cover:

- Informing users they are interacting with an AI system (Art. 50(1))
- Disclosure of emotion-recognition / biometric categorisation (Art. 50(3))
- Deepfake disclosure (Art. 50(4))
- AI-generated content marking (Art. 50(4))

The passport has first-class support for `ai_act_article_50` as one of its
eleven frameworks. An agent's `claims` map can carry per-sub-article status
(e.g. `transparency_50: compliant`) and the verifier enforces it just like
any other framework.

This server is the **keystone companion** to
[meok-compliance-gateway](https://github.com/meok-ai/meok-compliance-gateway),
which provides the underlying zero-knowledge and signature machinery. The
passport adds the *agent identity* and the *portable claim*. Together they
are the auditor's math.

---

## Verify offline

The full verification path uses only the public key, the signature, and
the fields in the passport. No phone-home. No `meok.ai` API call.

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from meok_compliance_passport_mcp.server import Passport, ISSUER_PUBLIC_KEY_HEX

def verify_with_public_key(passport: Passport) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(passport.public_key))
    payload = passport.canonical_payload()
    try:
        pub.verify(bytes.fromhex(passport.signature), payload)
        return True
    except InvalidSignature:
        return False
```

You can publish `ISSUER_PUBLIC_KEY_HEX` anywhere — on-chain, in DNS, in
a transparency log — and any third party can verify any passport without
ever talking to us.

---

## Next: A2A handshake

The `exchange_credentials` tool is the production primitive for the
Agent-to-Agent (A2A) handshake. In a typical flow:

1. Agent A calls `issue_passport(...)` once, at startup.
2. Agent B does the same.
3. When A and B meet, each presents its passport.
4. Each calls `verify_passport(peer_passport)` — **offline**.
5. Each calls `exchange_credentials(peer_passport, my_did)`.
6. The resulting `scope` is the agreed regulatory surface for the
   transaction.

Token TTL is 60 seconds by default, so this is meant to be re-run on
every meaningful interaction, not cached.

---

## The 11 supported frameworks

| Key                    | Framework                                                |
| ---------------------- | -------------------------------------------------------- |
| `eu_ai_act`            | EU AI Act (high-risk system obligations)                 |
| `ai_act_article_50`    | EU AI Act Article 50 (transparency)                      |
| `gdpr`                 | EU General Data Protection Regulation                    |
| `hipaa`                | US Health Insurance Portability and Accountability Act    |
| `soc2`                 | AICPA SOC 2 Trust Services Criteria                      |
| `iso_42001`            | ISO/IEC 42001 AI Management System                       |
| `nist_ai_rmf`          | NIST AI Risk Management Framework                        |
| `cra`                  | EU Cyber Resilience Act                                  |
| `dora`                 | EU Digital Operational Resilience Act                    |
| `nis2`                 | EU NIS2 Directive                                        |
| `code_of_practice`     | GPAI Code of Practice                                    |

Per-article schema hints for each framework are exported as
`REGULATION_SCHEMA` in `server.py`. They are not enforced at issue time —
they are a documentation surface for downstream tooling (a UI, a
gap-analysis engine, a regulator's report generator).

---

## Pricing

| Tier           | Quota                  | Price      |
| -------------- | ---------------------- | ---------- |
| **Free**       | 1,000 passports / mo   | $0         |
| **Pro**        | 100,000 passports / mo | $499 / mo  |
| **Enterprise** | Unlimited              | Talk to us |

Issue cost is on the order of a fraction of a cent — the bottleneck is
*signature verification*, which is `+1 ms` per check, offline. The
`exchange_credentials` handshake is free for both parties.

---

## Running the MCP server

The package exposes a console script:

```bash
meok-compliance-passport-mcp
```

This speaks the Model Context Protocol over stdio. To wire it into an MCP
host (Claude Desktop, Cursor, etc.), add it to your `mcp.json`:

```json
{
  "mcpServers": {
    "meok-compliance-passport": {
      "command": "meok-compliance-passport-mcp",
      "args": []
    }
  }
}
```

Once wired, the three tools above are callable as native MCP tools.

---

## Security notes

- The bundled private key is **deterministic and public**. It exists so
  the demo works out of the box and so anyone can reproduce the
  signature for verification. **Replace it with the meok-compliance-gateway
  KMS in production.** The constant `TEST_PRIVATE_KEY` in `server.py`
  is the single line to swap.
- Verification is intentionally offline. The server never makes a
  network call during `verify_passport` or `exchange_credentials`.
- `exchange_credentials` re-runs `verify_passport` internally. There
  is no fast path that skips signature checking.

---

## License

MIT. See [LICENSE](LICENSE).

© 2026 [meok.ai](https://meok.ai). The auditor's math is open.
