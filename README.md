# Shomer - the runtime control plane for enterprise AI agents

Shomer is an enforcement point for AI agents. Every agent action passes a single decision point that returns **ALLOW / DENY / REQUIRE_HUMAN / SANITIZE / OBSERVE**, with per-agent dollar budgets, cost metering, and a tamper-evident evidence ledger (hash chain + Ed25519-signed, externally verifiable checkpoints).

Not an agent framework. Not a model. Not a wrapper. Your agents, your models, your infrastructure. Self-hosted, no telemetry; the only outbound connections are to destinations you configure.

**Status:** pre-1.0. Working product with a full test suite (see below). No customers yet - we are looking for **design partners** (a 14-day observe-only pilot on one agent). See `docs/observe-pilot.md`.

## Quickstart

```bash
cd shomer
npm install
npm run start          # http://localhost:8787 - the API key is printed once and saved to data/DEV_KEY.txt
```

Second terminal:

```bash
python demo/refunds_agent.py   # a refunds agent that hits every decision type
```

Requirements: Node 18+, Python 3.9+ (the SDK has no third-party dependencies).

## What it does

| Decision | Meaning |
|---|---|
| `allow` | action approved, recorded, metered |
| `deny` | blocked: above a cap, tool not allowed, budget exhausted, runaway loop |
| `require_human` | human approval, cryptographically bound to the args hash |
| `sanitize` | PII redacted before the tool runs |
| `observe` | records the would-be decision without enforcing (pilot/rollout mode) |

- **Policy engine:** per-policy and per-agent `enforce`/`observe`; 7 policy types (PII redaction, rate limit, loop detection, thresholds with deny/require-human, tool allowlists, max call cost, daily dollar budgets).
- **Credential broker (MCP):** agents call the control plane, not the tool. The control plane holds the credential (env reference), executes the call server-side, and meters real usage. Pinned-IP connections with per-tool host/CIDR allowlists, no redirects, size caps.
- **MCP conformance:** `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call` over Streamable HTTP (JSON-RPC 2.0). Agent identity is derived from the agent-scoped API key.
- **Evidence ledger:** append-only hash chain; every decision - including denials - is written **before** the verdict is returned (fail-closed if the ledger cannot be written). Checkpoints are Ed25519-signed, written outside the data dir, and exported to an optional external sink (SIEM/WORM). The public key is exportable, so a reviewer verifies checkpoints without trusting the operator. Truncation/rollback is detected when a checkpoint exists beyond it.
- **Pilot tooling:** `npm run pilot` produces a cost report + evidence pack (JSON/PDF) for a time window.

## Architecture

```
 SDK (convenience)            CONTROL PLANE                         TOOLS
 ───────────────              ───────────────                       ─────
 sh.execute(tool)  ────────>  Policy Engine (7 policy types)
                              |  enforce | observe (per policy/agent)
                              v
                          Ledger (hash chain) ──> Ed25519 checkpoints + sink
                              |  log-BEFORE-act; append fails → DENY
                              v
 sh.call(tool)     ───────>  Credential Broker ──> executes the tool
                              |  credential injected server-side, pinned IP,
                              |  per-tool host/CIDR allowlists, no redirects
                              v
                          Metering: real usage -> pricing catalog -> cost_usd
```

## Tests

```bash
npm run test:all
```

Ten suites, each spinning up its own control plane on a temp data dir:

| Suite | What it proves |
|---|---|
| smoke | auth (401/403), the invariant *exactly one ledger entry per evaluate* for every decision type, observe mode, approval binding, evidence JSON+PDF |
| tamper | one mutated ledger line → verify fails |
| mcp | MCP conformance (initialize/tools/list/tools/call) + identity from key scope |
| bypass | direct tool call without the credential → 401; wrong agent scope → 403; legal calls metered from real usage; secrets never leak |
| concurrency | 200 parallel evaluates → valid chain, exactly 200 entries, unique contiguous seqs |
| truncation | deleting the last 10 ledger lines → detected as rollback |
| approval | approver identity is an authenticated per-human key, not a typed name |
| ssrf | pinned IPs, IPv4-mapped IPv6 and numeric encodings blocked, DNS-rebinding covered |
| failclosed | ledger store disabled mid-flight → evaluate fails closed (deny) |

## Offline / air-gapped

No telemetry; the only egress is what you configure. See `docs/offline-install.md` (folder copy or Docker image). SBOM: `npm run sbom`.

## Honest limitations

- No mTLS yet; no rate limit on the API itself; the dev key is admin-scoped - scope keys properly for production.
- The dashboard is a static single file served by the control plane.
- JSON/JSONL storage; Postgres migration when a design partner needs it.
- The "un-bypassable" property holds when agents have no credentials of their own and egress is network-restricted.

## License

AGPL-3.0. Commercial licensing available - contact the maintainer.

## Contributing

See `CONTRIBUTING.md`. Security issues: please do not open a public issue - contact the maintainer directly.