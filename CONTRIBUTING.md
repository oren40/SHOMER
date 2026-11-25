# Contributing to Shomer

Thanks for looking at Shomer - especially if you run agents in production and have opinions about what's missing.

## Ground rules

- **One decision point.** Features that bypass the policy engine (or the ledger) don't belong here. If you add a path, it goes through `evaluate()` and the broker.
- **Every decision is logged.** Denials included. A PR that adds a code path without a ledger entry will not be merged.
- **Fail closed.** If the ledger can't be written, the answer is `deny`.
- **Tests are the spec.** Every behavior change lands with a test. Run `npm run test:all` before opening a PR.

## Dev loop

```bash
npm install
npm run dev            # control plane with auto-restart
npm run test:all       # typecheck + 10 suites (each spawns its own server on a temp data dir)
python demo/refunds_agent.py
```

## Repo map

```
src/            control plane (TypeScript, tsx, no native deps)
  policy.ts     the policy engine (proposals, enforce/observe, log-before-act)
  broker.ts     credential broker + metering + destination policy (SSRF-hardened)
  ledger.ts     hash chain + Ed25519 checkpoints + sink export
  evidence.ts   evidence pack (JSON/PDF)
sdk/python/     zero-dependency Python SDK
dashboard/      single-file operator dashboard
scripts/        tests + demo tooling (seed, sink, pilot report, SBOM)
docs/           protocol + install + pilot docs
```

## Design partners

The fastest way to contribute right now: run the 14-day observe-only pilot on one of your agents and tell us what it failed to see. `docs/observe-pilot.md`.

## Security

Please don't open public issues for vulnerabilities. Contact the maintainer directly with a proof of concept.