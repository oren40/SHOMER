# 20-interview sprint — script and scoring

Goal: **10 conversations in each of two segments**, ending in **2 design partners that agree to a pilot with a date**. If after 20 conversations no one bites, that's a finding, not a failure — kill or re-scope, don't grind.

## Segments

**A — Regulated mid-market / enterprise (bank, insurance, fintech): CISO / Head of AI Risk / Head of Ops.** They have board pressure, exam questions (post-SR 26-2 / EU AI Act), and money.
**B — Large SaaS company (500+ employees): CTO / VP Platform / Head of AI.** They ship agents for customers, face COGS and liability, and have engineers.

## Recruiting

- Warm intros first (your network, portfolio founders, LinkedIn voice notes).
- 30 minutes, no slides, no demo unless they ask. Lead with their world, not our product.
- Book B before A (shorter sales cycles) so you can iterate the script on hard cases later.

## The script (30 min)

**Context (2 min).** "We research AI agent governance. Not selling anything — I want to understand how you run agents today. Can I take notes?"

**1. Current state (5 min)**
- How many agents are in production today? Who owns them — the team that built them, or someone else?
- Which ones touch money, customer data, or production systems?
- What happens today when an agent does something wrong? (Ask for the last real incident.)

**2. Control (6 min)**
- Can you show an auditor what an agent did last Tuesday?
- How do you stop one agent without stopping the whole system?
- Who can approve an agent action above a dollar threshold, and how is that recorded?
- Do you know your cost per agent — not per project, per agent?

**3. Pain / budget (6 min)**
- What did the last agent incident or overrun cost you (time, money, trust)?
- If solving governance blocked the next 3 agent rollouts, how painful is that?
- Where does the budget for this come from — security, platform, or the business unit?

**4. AlternWhat would make you switch (5 min)**
- What would you have to see in the first 14 days to trust it in production?
- What's the one thing that would make you say "absolutely not"?

**5. Close (3 min)**
- "I'm not ready to sell. Would you run a 2-week observe-only pilot on one agent — we connect, we report, nothing is blocked, you keep the evidence?" → if yes: **get a date and an agent owner on the call.**

## Scoring (fill after each call, 1-5)

| Signal | Score |
|---|---|
| Pain is specific and recent (named incident) | |
| Has a named owner for agent governance | |
| Can name a pilot agent + owner today | |
| Pilot agreed with a date | |
| Budget path identified | |

**Library of quotes:** log verbatim. Two "we didn't know we could know that" moments from the pilot reports are worth more than any slide.

## The bar for "validated"

- ≥10 qualified conversations (agents in prod + a named owner).
- ≥5 "specific recent pain" scores ≥4.
- **2 design partners with a signed pilot start date.**
Everything below that = keep interviewing, don't build features.