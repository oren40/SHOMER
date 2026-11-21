# Offline / air-gapped install

Shomer has **no telemetry**: the only outbound connections are to destinations you configure explicitly:

- broker tool destinations (HTTP/Shell tools you register), and
- the optional checkpoint sink (`SHOMER_CHECKPOINT_SINK_URL`).

There is no license check, no phone-home, no analytics.

## Option A - copy the folder with `node_modules`

On a machine with internet access:

```bash
cd shomer
npm install
npm run sbom          # produce shomer-sbom.json for procurement
```

Copy the entire folder **including `node_modules`** (no native modules; the only platform binary is esbuild's, already installed) plus `package-lock.json` to the air-gapped host. Then:

```bash
node --version        # >= 18 required
npm run start         # http://localhost:8787
```

No registry access is needed at runtime.

## Option B - build the Docker image once

Build requires network access once (base image + npm packages); the running container reaches only configured destinations.

```bash
docker build -t shomer:0.2.2 .
docker save shomer:0.2.2 | gzip > shomer-0.2.2.tar.gz   # transfer to the host
gunzip -c shomer-0.2.2.tar.gz | docker load
docker run -p 8787:8787 -v shomer_data:/app/data shomer:0.2.2
```

## Environment

| Variable | Default | Notes |
|---|---|---|
| `PORT` | `8787` | HTTP port |
| `SHOMER_ADMIN_KEY` | *(none)* | first-boot admin key (otherwise a dev key is printed once and saved to `data/DEV_KEY.txt`) |
| `SHOMER_CHECKPOINT_DIR` | `<data>/../shomer-checkpoints` | outside the data dir by design |
| `SHOMER_CHECKPOINT_KEY_PATH` | `<data>/../shomer-keys/checkpoint_ed25519.pem` | **keep outside the data dir**: on POSIX restrict with `chmod 600`; on Windows use ACLs that grant access only to the service account |
| `SHOMER_CHECKPOINT_SINK_URL` | *(none)* | optional external sink (SIEM / customer WORM); best-effort delivery, status at `GET /api/checkpoints` |
| `SHOMER_CHECKPOINT_EVERY` / `SHOMER_CHECKPOINT_INTERVAL_S` | `25` / `300` | checkpoint cadence (records or seconds) |
| `SHOMER_BROKER_MAX_RESPONSE_BYTES` | `1000000` | response cap per broker call |

## Verifying a deployment offline

```bash
curl -s http://localhost:8787/v1/ledger/verify -H "Authorization: Bearer $KEY"
# -> {"valid":true,...,"checkpoint":{...},"public_key_fp":"..."}
```

Hand the public key PEM (`GET /api/checkpoints`) to an external reviewer: they can verify every checkpoint without trusting the operator, and truncation/rollback is detected as long as one checkpoint exists beyond the removed records. The **open window** = records since the last checkpoint (see `/api/checkpoints` for `records_since_checkpoint` and `seconds_since_checkpoint`).