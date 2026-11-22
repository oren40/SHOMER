/**
 * sink_mock.mjs - a stand-in external checkpoint sink (SIEM / customer WORM).
 * Receives Ed25519-signed checkpoints and appends them to sink/checkpoints.jsonl.
 *
 * Usage:
 *   node scripts/sink_mock.mjs                     # listens on :8788
 *   SHOMER_CHECKPOINT_SINK_URL=http://localhost:8788/checkpoint npm run start
 *   # then check delivery:  GET /api/checkpoints  ->  export: {ok: true}
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "sink");
const PORT = Number(process.env.SINK_PORT || 8788);

fs.mkdirSync(OUT, { recursive: true });
fs.appendFileSync(path.join(OUT, "checkpoints.jsonl"), "");

const server = http.createServer((req, res) => {
  if (req.method === "GET") {
    const lines = fs.readFileSync(path.join(OUT, "checkpoints.jsonl"), "utf8").trim().split("\n").filter(Boolean);
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ received: lines.length, checkpoints: lines.map((l) => JSON.parse(l)) }));
  }
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let cp;
    try {
      cp = JSON.parse(body);
    } catch {
      res.writeHead(400);
      return res.end("bad json");
    }
    fs.appendFileSync(path.join(OUT, "checkpoints.jsonl"), JSON.stringify(cp) + "\n");
    console.log(`[sink] checkpoint seq=${cp.seq} ts=${cp.ts} sig=${String(cp.sig).slice(0, 16)}...`);
    res.writeHead(202, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, stored: true }));
  });
});

server.listen(PORT, () => console.log(`checkpoint sink listening on http://localhost:${PORT} (GET to inspect, log: sink/checkpoints.jsonl)`));