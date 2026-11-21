# Observe-only pilot - 14-day protocol

The pilot proves one thing on ONE agent: **Shomer sees everything, and the data is worth money** - before anything is required to change in the customer's stack.

## Entry criteria (before day 0)

1. Shomer deployed (Docker image or folder copy - see `docs/offline-install.md`).
2. One agent selected with a named owner and a business process attached (e.g. refunds, invoice triage, code review).
3. The agent's key is scoped to it: `agent:<id>`, with the rest of the key's scopes empty.
4. The agent is in **observe** mode: `PATCH /api/agents/<id> {"enforcement":"observe"}`.

In observe mode Shomer records the would-be decision for every action (including the ones it *would* have blocked) without enforcing. Nothing in the customer's runtime is allowed to change during the pilot.

## Day 0 - instrumentation (30 minutes)

- Wire the SDK into one code path of the agent: `Shomer(agent_id="<id>", api_key="<agent key>")`, wrap the sensitive actions with `sh.execute(tool, args, estimated_cost_usd=...)`. Or route tool calls through `sh.call(tool, args)` (broker) so credentials never sit with the agent.
- Confirm: `GET /api/overview` counts actions; `GET /api/approvals` reflects human-in-the-loop.
- Prefer `sh.call()` for tools that hold credentials - that is the path proving the "un-bypassable" property.

## Day 7 - mid-pilot checkpoint (30 minutes)

```bash
npm run pilot -- --agent <id> --days 7
```

Review with the owner: total spend, blocked/would-be blocks, approvals pending, anomalies. Ask for one concrete "we did not know X" sentence.

## Day 14 - close

```bash
npm run pilot -- --agent <id> --days 14
```

Deliverables from the run (written to `pilot-out/`):
- **Cost report** (markdown): per-tool actions, blocked counts, block reasons, metered spend.
- **Evidence pack** (JSON + PDF): what was allowed, what happened, what it cost, who approved what, chain verification + Ed25519 checkpoint + public key. Internal audit can verify it themselves (docs/offline-install.md#verifying-a-deployment-offline).

## Success criteria (agreed up front)

| Criterion | Target |
|---|---|
| Actions governed | >= 90% of the agent's actions in the period |
| Would-be blocks revealed | >= 3 patterns (runaway loop, budget overrun, hard-cap, tool misuse) |
| Identified waste / avoided overrun | a dollar figure agreed with the owner (e.g. "we'd have spent $X more") |
| Evidence accepted | the pack is accepted by the owner's internal audit/risk reviewer |
| Next step | the owner agrees to flip the agent (or a second agent) to `enforce` with a date |

## Exit and conversion

- Week 3: flip to `enforce` for the piloted agent - kill switches, budgets, human approvals now ACTIVE, no scare stories (the pilot already showed what would have been blocked).
- Week 4: expand to 2-3 agents in the same team, then negotiate the commercial motion (per-managed-agent or % of managed inference spend).

## Rules of the pilot (non-negotiable)

- Observe only - no policy changes mid-pilot without a reset of baselines.
- One agent, one code path. Breadth later.
- The pilot ends with a decision, not a summary. If the criteria are not met, that is a finding, not a failure - kill it early and tell the customer why.