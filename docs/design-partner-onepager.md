# Shomer — control plane for AI agents (design-partner one-pager)

**The problem you already have:** your teams are shipping AI agents into production faster than anyone can govern them. In 2026 only ~17% of enterprises had deployed agents; 60%+ plan to within two years. Meanwhile: 40%+ of agentic projects will be cancelled by end of 2027 (cost, unclear value, inadequate risk controls), inference costs per agent workflow are set to rise 5x by 2028, and ~80% of enterprises lack mature agent governance (Deloitte 2026).

**What Shomer is:** a runtime control plane that sits between your agents and everything they touch. Every agent action passes one enforcement point that decides ALLOW / DENY / REQUIRE_HUMAN / SANITIZE / OBSERVE — with dollar budgets per agent, cost attribution, and a tamper-evident evidence ledger (hash chain + Ed25519-signed checkpoints you can verify yourself).

**What it is not:** not an agent framework, not a model, not a wrapper. Your agents, your models, your infrastructure. Shomer can run fully inside your environment; its runtime has no telemetry and no outbound calls except to destinations you configure.

## What you get in 14 days (observe-only pilot)

1. **We deploy, you connect one agent** (~30 min of your engineer's time; SDK or MCP endpoint).
2. **Everything is recorded, nothing is blocked.** For 14 days Shomer records what it *would* have allowed, blocked, or escalated.
3. **On day 14 you get a report + an evidence pack:** actions governed, blocked patterns (runaway loops, budget overruns, hard caps, tool misuse), metered spend per agent/tool, plus a PDF/JSON pack your own audit team can verify (public-key checkpoints, no trust in us required).
4. **You decide.** Flip the agent to enforce when you're ready. No platform commitment.

**Success we sign up for:** ≥90% of the agent's actions governed, ≥3 revealed risk patterns, a quantified avoided overrun, and your audit reviewer accepting the evidence pack.

## Why it's hard to replace

- **Position:** enforcement must be inline in the request path — retrofitting it means re-wiring every agent.
- **Evidence:** the hash-chained, checkpoint-signed ledger is the system of record for what agents did; history migrates with you or it doesn't exist.
- **Neutrality:** model- and cloud-agnostic (incl. on-prem inference); no lock-in to a model vendor's stack.

## The ask

A 30-minute call with the owner of one production agent (refunds, triage, code review, invoices). If it's relevant, we start the 14-day pilot the same week.

Contact: __________________