/**
 * SBOM: CycloneDX-lite JSON built from package.json + package-lock.json.
 * Usage: npm run sbom   ->  ./shomer-sbom.json
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lockPath = path.join(root, "package-lock.json");
  const lock = fs.existsSync(lockPath) ? JSON.parse(fs.readFileSync(lockPath, "utf8")) : { packages: {} };

  const components = [];
  for (const [p, meta] of Object.entries(lock.packages || {})) {
    if (!p || !meta?.version) continue;
    const name = p.replace(/^node_modules\//, "").replace(/.*node_modules\//, "");
    components.push({
      type: "library",
      name,
      version: meta.version,
      purl: "pkg:npm/" + name.replace("@", "%40").replace("/", "%2f") + "@" + meta.version,
      scope: meta.dev ? "optional" : "required",
    });
  }
  if (components.length === 0) {
    for (const [name, version] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
      components.push({
        type: "library",
        name,
        version: String(version).replace(/^[\^~]/, ""),
        purl: "pkg:npm/" + name + "@" + String(version).replace(/^[\^~]/, ""),
        scope: name in (pkg.dependencies || {}) ? "required" : "optional",
      });
    }
  }

  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      component: { type: "application", name: "shomer", version: "0.2.2" },
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "shomer", name: "sbom.mjs" }],
    },
    components,
  };
  const out = path.join(root, "shomer-sbom.json");
  fs.writeFileSync(out, JSON.stringify(bom, null, 2));
  console.log(`SBOM written: ${out} (${components.length} components)`);
  console.log("Note: build with 'npm run sbom' after every dependency change; the SBOM is generated from the lockfile, not the registry.");
}
main();