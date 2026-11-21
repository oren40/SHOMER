# Shomer — the runtime control plane for enterprise AI agents

Runtime control layer for enterprise AI agents. Every agent action passes an enforcement point that decides:

**ALLOW** · **DENY** · **REQUIRE_HUMAN** · **SANITIZE** · **OBSERVE** — with real-time dollar budgets, cost attribution, and a tamper-evident evidence ledger (hash chain + signed checkpoints).

v0.2 adds: API-key auth, an un-bypassable credential broker, server-side cost metering, observe mode, and the Evidence Pack. v0.2.2 adds: Ed25519-signed checkpoints with external export, MCP conformance (Streamable HTTP), SSRF-hardened broker, authenticated approver identity, serialized appends (concurrency-safe), offline packaging.

## Quickstart

```bash
cd shomer
npm install
npm run start          # http://localhost:8787 - the API key is printed once and saved to data/DEV_KEY.txt

# second terminal:
python demo/refunds_agent.py   # the demo reads the key automatically
```

## Demo (2 minutes)

| Step | Decision |
|---|---|
| small refund $18 | `allow` |
| args with an email | `sanitize` — PII redacted before the tool runs |
| refund $320 | `require_human` — human approval, cryptographically bound to the args hash |
| refund $5000 | `deny` — hard cap |
| same call x4 | `runaway_loop_detected` — circuit breaker |
| burst of notifications | `daily_budget_exhausted` — even cheap calls get blocked |

Observe mode: flip a policy or an agent to `observe` and it records the would-be decision without enforcing. Roll out as observe -> enforce.

## Architecture

```
 SDK (convenience)            CONTROL PLANE                         TOOLS
 ───────────────              ───────────────                       ─────
 sh.execute(tool)  ────────>  Policy Engine (7 policy types)
                              |  enforce | observe (per policy / per agent)
                              v
                          Ledger (hash-chain) ──> signed checkpoints (outside data dir)
                              |  log-BEFORE-act; if the append fails -> DENY (fail-closed)
                              v
 sh.call(tool)     ───────>  Credential Broker ──> executes the tool
                              |  credential injected server-side; the agent never sees it
                              v
                          Metering: real usage -> pricing catalog -> cost_usd
```

## API

**Agents (scope `agent:<id>`)**
- `POST /v1/evaluate` · `POST /v1/complete`
- `POST /mcp/v1/tools/{tool}/call` · `POST /mcp` (JSON-RPC `tools/call`)

**Ops (scope `dashboard`)** — overview, agents (pause / kill / observe), policies (mode flip), decisions, approvals (with identity + args-hash binding), evidence.

**Admin** — `POST/GET/DELETE /api/keys`, `/api/credentials` (broker registry), `/api/pricing`.

**Evidence** — `GET /api/evidence?agent_id=&from=&to=` (JSON) · `.../export?format=pdf|json`

## Tests

```bash
npm run test:all     # typecheck + smoke + tamper + MCP + bypass + concurrency + truncation + approval + fail-closed
```

| Test | What it proves |
|---|---|
| smoke | auth 401/403; invariant: exactly one ledger entry per evaluate for every decision type; observe mode; approval args-hash binding; evidence JSON + PDF |
| tamper | one mutated ledger line -> `verify` MUST fail |
| bypass | direct call to the tool without the secret -> 401; wrong agent scope -> 403; a legal call goes through the broker, is metered from real usage, and the secret never reaches the caller |
| failclosed | deleting the data dir mid-flight -> evaluate returns `deny` (ledger_append_failed) |

## Evidence Pack — framing

The pack documents what an agent was allowed to do, what it actually did, what it cost, and who approved what — **as evidence for your internal controls** (internal audit / risk review).

It does **not** assert regulatory conformity: SR 26-2 (April 2026) explicitly excludes generative and agentic AI, and under the EU AI Act the obligation sits with the deploying organization, not with a vendor. The pack supplies the evidence; it does not issue a certificate.

## Security — known limitations, as-is

- No mTLS yet (planned for high-assurance deployments); no rate limit on the API itself.
- The dev key is admin-scoped and printed to the console — for production use `SHOMER_ADMIN_KEY` + narrowly scoped keys.
- Checkpoints: `SHOMER_CHECKPOINT_DIR` (defaults outside the data dir) + `SHOMER_CHECKPOINT_KEY` (recommended via env; otherwise a key is generated inside `data/`, which protects against mutation and rewrite but not against filesystem access).
- In the ledger, args are stored as a hash + a redacted preview; the full payload is kept only for human approvals.
- The dashboard is a static single file served by the control plane (Phase 3: Next.js app).

## Roadmap

Deferred: Next.js dashboard, Postgres (when a design partner needs it), OpenTelemetry + LangChain callbacks, multi-tenancy, a fully MCP-native proxy (currently a shim), model routing / tiering (the basis for outcome-based pricing).

## Trust model (v0.2.2)

- **Appends are serialized.** Every /v1/evaluate is queued, so log-before-act and chain integrity hold under concurrent load (200 parallel calls tested: valid chain, exactly 200 entries, unique contiguous seqs).
- **Checkpoints are Ed25519-signed**, written outside the data dir, every 25 records or 300s (env-tunable), and exported to an optional external sink (`SHOMER_CHECKPOINT_SINK_URL`; delivery status at `GET /api/checkpoints`). The **public key is exportable**, so a reviewer verifies checkpoints without trusting the operator. Deleting tail records is detected when any checkpoint exists beyond them (`ledger_behind_checkpoint`).
- **Approvals are bound to an authenticated principal** (a per-human dashboard key) and to the args hash of the exact decision. A typed name is kept as a note, never as evidence.
- **MCP conformance:** `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call` over Streamable HTTP (JSON-RPC 2.0). Connect any MCP client to `POST http://<host>:8787/mcp` with `Authorization: Bearer <agent-scoped key>` and `params._agent_id` in tools/call - zero code changes.

## Packaging (offline-ready)

```bash
npm run sbom                 # CycloneDX-lite -> shomer-sbom.json
docker build -t shomer .     # runtime makes NO outbound calls (see .dockerignore, Dockerfile)
```

Air-gapped install: copy the folder with node_modules, run `npm run start` - details in docs/offline-install.md.