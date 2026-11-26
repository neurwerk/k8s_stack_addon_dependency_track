import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const targets = JSON.parse(readFileSync("/work/repositories.json", "utf8"));
for (const target of targets) {
  const result = spawnSync("cdxgen", [
    "-r", target.path, "--no-install-deps", "--fail-on-error",
    "-o", `/work/${target.id}.cdx.json`,
  ], {
    stdio: "ignore",
    timeout: 900_000,
    env: { ...process.env, FETCH_LICENSE: "true", CDXGEN_DEBUG_MODE: "false" },
  });
  if (result.error || result.status !== 0) {
    writeFileSync(`/work/${target.id}.failed`, "");
  }
}
