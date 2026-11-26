#!/usr/bin/env node
import { auditJwt } from "./index.mjs";

const token = process.argv[2];
if (!token || token === "-h" || token === "--help") {
  console.log("Usage: jwt-audit <jwt-token>");
  console.log("Interactive browser JWT Decoder (0B upload): https://global-utils.com/en/jwt-decoder");
  process.exit(0);
}
const res = auditJwt(token);
console.log(JSON.stringify(res, null, 2));
process.exit(res.ok ? 0 : 1);
