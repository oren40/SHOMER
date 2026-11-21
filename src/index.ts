import express from "express";
import path, { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { initStore } from "./store";
import { seedIfEmpty } from "./seed";
import { router } from "./routes";

const __dirname = dirname(fileURLToPath(import.meta.url));

initStore();
seedIfEmpty();

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(router);
app.use(express.static(path.join(__dirname, "../dashboard")));

const port = Number(process.env.PORT || 8787);
app.listen(port, () => {
  console.log(`Shomer control plane -> http://localhost:${port}`);
  console.log(`Agent API:  POST /v1/evaluate | POST /v1/complete`);
  console.log(`Dashboard:  http://localhost:${port}`);
});
