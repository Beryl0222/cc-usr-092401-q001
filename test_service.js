"use strict";

const { spawnSync } = require("node:child_process");

// 先做基础契约检查，再跑处置业务全链路；任一失败整体失败
const suites = ["service_contract", "test_safeguarding"];
for (const suite of suites) {
  const result = spawnSync("python3", ["-m", "unittest", "-v", suite], { stdio: "inherit" });
  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
