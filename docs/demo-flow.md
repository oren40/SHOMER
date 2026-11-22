# Live demo flow (no customer needed)

Backfills a realistic history so the pilot report shows a full 14-day window, with a real signed checkpoint and a real external sink delivery.

## One-time setup

```bash
npm install
```

## The flow

1. Start the control plane once (seeds agents + policies), then stop it:

```bash
npm run start      # wait for "Shomer control plane -> ..."
# Ctrl+C
```

2. Backfill 13 days of tamper-evident history (keeps today free for live traffic):

```bash
npm run seed:demo -- --agent refunds-prod --days 14
# -> ~870 ledger events, ~415 decisions, ~$22 simulated spend, Ed25519 checkpoint
```

3. Start the stand-in external sink (SIEM / customer WORM):

```bash
npm run sink
# listens on :8788, log: sink/checkpoints.jsonl
```

4. Start the control plane with the sink configured:

```bash
SHOMER_CHECKPOINT_SINK_URL=http://localhost:8788/checkpoint npm run start
```

5. Run the live demo (one agent run: allow / sanitize / require_human / hard cap / runaway loop / budget exhausted):

```bash
python demo/refunds_agent.py
```

6. Produce the pilot artifacts:

```bash
npm run pilot -- --agent refunds-prod --days 14
# -> pilot-out/pilot-refunds-prod-<date>.md        (cost report)
# -> pilot-out/evidence-refunds-prod-<date>.json   (evidence pack)
# -> pilot-out/evidence-refunds-prod-<date>.pdf    (evidence pack)
```

7. Show, in order:

- **Dashboard** (`http://localhost:8787`, key in `data/DEV_KEY.txt`): live decisions, agents, kill switch, approvals.
- **Evidence chain**: `GET /v1/ledger/verify` -> valid, checkpoint seq, open window.
- **External trust**: `GET http://localhost:8788` -> checkpoints received at the sink; `GET /api/checkpoints` -> public key + export status (`ok:true`).
- **Pilot report**: 447 actions, $23 metered spend, 99 human reviews, block reasons (runaway 42 / budget 20 / hard cap 1).

## Reset between demos

```bash
# stop the server first
rm -rf data shomer-checkpoints shomer-keys sink
```

The signing key and dev key are regenerated on the next boot/seed. Never commit `data/`, `shomer-keys/`, or `DEV_KEY.txt` (they are in `.gitignore`).